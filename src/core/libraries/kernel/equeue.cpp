// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <thread>

#include "common/assert.h"
#include "common/debug.h"
#include "common/logging/log.h"
#include "core/libraries/kernel/equeue.h"
#include "core/libraries/kernel/orbis_error.h"
#include "core/libraries/libs.h"

namespace Libraries::Kernel {

// Events are uniquely identified by id and filter.

bool EqueueInternal::AddEvent(EqueueEvent& event) {
    std::scoped_lock lock{m_mutex};
    event.time_added = std::chrono::steady_clock::now();
    const auto& it = std::ranges::find(m_events, event);
    if (it != m_events.cend()) {
        *it = std::move(event);
    } else {
        m_events.emplace_back(std::move(event));
    }
    m_cond.notify_one(); // Notify in case waiting threads need to check timers
    return true;
}

bool EqueueInternal::RemoveEvent(u64 id, s16 filter) {
    bool has_found = false;
    std::scoped_lock lock{m_mutex};

    const auto& it = std::ranges::find_if(m_events, [id, filter](auto& ev) {
        return ev.event.ident == id && ev.event.filter == filter;
    });
    if (it != m_events.cend()) {
        m_events.erase(it);
        has_found = true;
    }
    return has_found;
}

int EqueueInternal::WaitForEvents(SceKernelEvent* ev, int num, u32 micros) {
    int count = 0;
    const auto predicate = [&] {
        count = GetTriggeredEvents(ev, num);
        return count > 0;
    };
    std::unique_lock lock{m_mutex};
    if (micros == 0) {
        m_cond.wait(lock, predicate);
    } else {
        auto now = std::chrono::steady_clock::now();
        std::chrono::microseconds min_timeout{micros};
        // Adjust timeout for timer events
        for (const auto& event : m_events) {
            if (event.event.filter == SceKernelEvent::Filter::HrTimer && event.event.data > 0) {
                auto time_left = std::chrono::duration_cast<std::chrono::microseconds>(
                    event.time_added + std::chrono::microseconds{event.event.data} - now);
                if (time_left > std::chrono::microseconds{0}) {
                    min_timeout = std::min(min_timeout, time_left);
                }
            }
        }
        m_cond.wait_for(lock, min_timeout, predicate);
        count = GetTriggeredEvents(ev, num); // Recheck after waiting
    }
    lock.unlock();
    if (count > 0 && ev[0].flags & SceKernelEvent::Flags::OneShot) {
        for (auto ev_id = 0u; ev_id < count; ++ev_id) {
            RemoveEvent(ev[ev_id].ident, ev[ev_id].filter);
        }
    }
    return count;
}

bool EqueueInternal::TriggerEvent(u64 ident, s16 filter, void* trigger_data) {
    bool has_found = false;
    {
        std::scoped_lock lock{m_mutex};
        for (auto& event : m_events) {
            if (event.event.ident == ident && event.event.filter == filter) {
                if (filter == SceKernelEvent::Filter::VideoOut) {
                    event.TriggerDisplay(trigger_data);
                } else {
                    event.Trigger(trigger_data);
                }
                has_found = true;
            }
        }
    }
    m_cond.notify_one();
    return has_found;
}

int EqueueInternal::GetTriggeredEvents(SceKernelEvent* ev, int num) {
    int count = 0;
    for (auto& event : m_events) {
        if (event.IsTriggered()) {
            // Event should not trigger again
            event.ResetTriggerState();

            if (event.event.flags & SceKernelEvent::Flags::Clear) {
                event.Clear();
            }
            ev[count++] = event.event;
            if (count == num) {
                break;
            }
        }
    }

    return count;
}

extern boost::asio::io_context io_context;
extern void KernelSignalRequest();

static constexpr auto HrTimerSpinlockThresholdUs = 1200u;

static void SmallTimerCallback(const boost::system::error_code& error, SceKernelEqueue eq,
                               SceKernelEvent kevent) {
    static EqueueEvent event;
    event.event = kevent;
    event.event.data = HrTimerSpinlockThresholdUs;
    eq->AddSmallTimer(event);
    eq->TriggerEvent(kevent.ident, SceKernelEvent::Filter::HrTimer, kevent.udata);
}

int PS4_SYSV_ABI sceKernelCreateEqueue(SceKernelEqueue* eq, const char* name) {
    if (eq == nullptr) {
        LOG_ERROR(Kernel_Event, "Event queue is null!");
        return ORBIS_KERNEL_ERROR_EINVAL;
    }
    if (name == nullptr) {
        LOG_ERROR(Kernel_Event, "Event queue name is null!");
        return ORBIS_KERNEL_ERROR_EINVAL;
    }

    // Maximum is 32 including null terminator
    static constexpr size_t MaxEventQueueNameSize = 32;
    if (std::strlen(name) > MaxEventQueueNameSize) {
        LOG_ERROR(Kernel_Event, "Event queue name exceeds 32 bytes!");
        return ORBIS_KERNEL_ERROR_ENAMETOOLONG;
    }

    LOG_INFO(Kernel_Event, "name = {}", name);

    *eq = new EqueueInternal(name);
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceKernelDeleteEqueue(SceKernelEqueue eq) {
    if (eq == nullptr) {
        return ORBIS_KERNEL_ERROR_EBADF;
    }

    delete eq;
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceKernelWaitEqueue(SceKernelEqueue eq, SceKernelEvent* ev, int num, int* out,
                                     SceKernelUseconds* timo) {
    LOG_TRACE(Kernel_Event, "equeue = {} num = {}", eq->GetName(), num);
    if (eq == nullptr) return ORBIS_KERNEL_ERROR_EBADF;
    if (ev == nullptr) return ORBIS_KERNEL_ERROR_EFAULT;
    if (num < 1) return ORBIS_KERNEL_ERROR_EINVAL;

    if (timo == nullptr) {
        *out = eq->WaitForEvents(ev, num, 0);
    } else if (*timo == 0) {
        *out = eq->GetTriggeredEvents(ev, num);
    } else {
        *out = eq->WaitForEvents(ev, num, *timo);
    }
    return (*out == 0 && timo) ? ORBIS_KERNEL_ERROR_ETIMEDOUT : ORBIS_OK;
}

s32 PS4_SYSV_ABI sceKernelAddHRTimerEvent(SceKernelEqueue eq, int id, timespec* ts, void* udata) {
    if (eq == nullptr) {
        return ORBIS_KERNEL_ERROR_EBADF;
    }

    if (ts->tv_sec > 100 || ts->tv_nsec < 100'000) {
        return ORBIS_KERNEL_ERROR_EINVAL;
    }
    ASSERT(ts->tv_nsec > 1000); // assume 1us resolution
    const auto total_us = ts->tv_sec * 1000'000 + ts->tv_nsec / 1000;

    EqueueEvent event{};
    event.event.ident = id;
    event.event.filter = SceKernelEvent::Filter::HrTimer;
    event.event.flags = SceKernelEvent::Flags::Add | SceKernelEvent::Flags::OneShot;
    event.event.fflags = 0;
    event.event.data = total_us;
    event.event.udata = udata;

    // HR timers cannot be implemented within the existing event queue architecture due to the
    // slowness of the notification mechanism. For instance, a 100us timer will lose its precision
    // as the trigger time drifts by +50-700%, depending on the host PC and workload. To address
    // this issue, we use a spinlock for small waits (which can be adjusted using
    // `HrTimerSpinlockThresholdUs`) and fall back to boost asio timers if the time to tick is
    // large. Even for large delays, we truncate a small portion to complete the wait
    // using the spinlock, prioritizing precision.
    if (total_us < HrTimerSpinlockThresholdUs) {
        return eq->AddSmallTimer(event) ? ORBIS_OK : ORBIS_KERNEL_ERROR_ENOMEM;
    }

    event.timer = std::make_unique<boost::asio::steady_timer>(
        io_context, std::chrono::microseconds(total_us - HrTimerSpinlockThresholdUs));

    event.timer->async_wait(std::bind(SmallTimerCallback, std::placeholders::_1, eq, event.event));

    if (!eq->AddEvent(event)) {
        return ORBIS_KERNEL_ERROR_ENOMEM;
    }

    KernelSignalRequest();

    return ORBIS_OK;
}

int PS4_SYSV_ABI sceKernelDeleteHRTimerEvent(SceKernelEqueue eq, int id) {
    if (eq == nullptr) {
        return ORBIS_KERNEL_ERROR_EBADF;
    }
    return eq->RemoveEvent(id, SceKernelEvent::Filter::HrTimer) ? ORBIS_OK : ORBIS_KERNEL_ERROR_ENOENT;
}

int PS4_SYSV_ABI sceKernelAddUserEvent(SceKernelEqueue eq, int id) {
    if (eq == nullptr) {
        return ORBIS_KERNEL_ERROR_EBADF;
    }

    EqueueEvent event{};
    event.event.ident = id;
    event.event.filter = SceKernelEvent::Filter::User;
    event.event.udata = 0;
    event.event.flags = SceKernelEvent::Flags::Add;
    event.event.fflags = 0;
    event.event.data = 0;

    return eq->AddEvent(event) ? ORBIS_OK : ORBIS_KERNEL_ERROR_ENOMEM;
}

int PS4_SYSV_ABI sceKernelAddUserEventEdge(SceKernelEqueue eq, int id) {
    if (eq == nullptr) {
        return ORBIS_KERNEL_ERROR_EBADF;
    }

    EqueueEvent event{};
    event.event.ident = id;
    event.event.filter = SceKernelEvent::Filter::User;
    event.event.udata = 0;
    event.event.flags = SceKernelEvent::Flags::Add | SceKernelEvent::Flags::Clear;
    event.event.fflags = 0;
    event.event.data = 0;

    return eq->AddEvent(event) ? ORBIS_OK : ORBIS_KERNEL_ERROR_ENOMEM;
}

void* PS4_SYSV_ABI sceKernelGetEventUserData(const SceKernelEvent* ev) {
    ASSERT(ev);
    return ev->udata;
}

u64 PS4_SYSV_ABI sceKernelGetEventId(const SceKernelEvent* ev) {
    return ev->ident;
}

int PS4_SYSV_ABI sceKernelTriggerUserEvent(SceKernelEqueue eq, int id, void* udata) {
    if (eq == nullptr) {
        return ORBIS_KERNEL_ERROR_EBADF;
    }

    if (!eq->TriggerEvent(id, SceKernelEvent::Filter::User, udata)) {
        return ORBIS_KERNEL_ERROR_ENOENT;
    }
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceKernelDeleteUserEvent(SceKernelEqueue eq, int id) {
    if (eq == nullptr) {
        return ORBIS_KERNEL_ERROR_EBADF;
    }

    if (!eq->RemoveEvent(id, SceKernelEvent::Filter::User)) {
        return ORBIS_KERNEL_ERROR_ENOENT;
    }
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceKernelGetEventFilter(const SceKernelEvent* ev) {
    return ev->filter;
}

u64 PS4_SYSV_ABI sceKernelGetEventData(const SceKernelEvent* ev) {
    return ev->data;
}

void RegisterEventQueue(Core::Loader::SymbolsResolver* sym) {
    LIB_FUNCTION("D0OdFMjp46I", "libkernel", 1, "libkernel", 1, 1, sceKernelCreateEqueue);
    LIB_FUNCTION("jpFjmgAC5AE", "libkernel", 1, "libkernel", 1, 1, sceKernelDeleteEqueue);
    LIB_FUNCTION("fzyMKs9kim0", "libkernel", 1, "libkernel", 1, 1, sceKernelWaitEqueue);
    LIB_FUNCTION("vz+pg2zdopI", "libkernel", 1, "libkernel", 1, 1, sceKernelGetEventUserData);
    LIB_FUNCTION("4R6-OvI2cEA", "libkernel", 1, "libkernel", 1, 1, sceKernelAddUserEvent);
    LIB_FUNCTION("WDszmSbWuDk", "libkernel", 1, "libkernel", 1, 1, sceKernelAddUserEventEdge);
    LIB_FUNCTION("R74tt43xP6k", "libkernel", 1, "libkernel", 1, 1, sceKernelAddHRTimerEvent);
    LIB_FUNCTION("J+LF6LwObXU", "libkernel", 1, "libkernel", 1, 1, sceKernelDeleteHRTimerEvent);
    LIB_FUNCTION("F6e0kwo4cnk", "libkernel", 1, "libkernel", 1, 1, sceKernelTriggerUserEvent);
    LIB_FUNCTION("LJDwdSNTnDg", "libkernel", 1, "libkernel", 1, 1, sceKernelDeleteUserEvent);
    LIB_FUNCTION("mJ7aghmgvfc", "libkernel", 1, "libkernel", 1, 1, sceKernelGetEventId);
    LIB_FUNCTION("23CPPI1tyBY", "libkernel", 1, "libkernel", 1, 1, sceKernelGetEventFilter);
    LIB_FUNCTION("kwGyyjohI50", "libkernel", 1, "libkernel", 1, 1, sceKernelGetEventData);
}

} // namespace Libraries::Kernel
