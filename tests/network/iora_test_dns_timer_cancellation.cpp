// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_dns_timer_cancellation.cpp
/// \brief Test DNS transport timer cancellation functionality
///
/// This test validates that retry timers are properly cancelled when
/// queries complete early, preventing resource leaks.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/core/timer.hpp"
#include <chrono>
#include <thread>
#include <atomic>

using namespace iora::core;

TEST_CASE("TimerService Cancellation Functionality", "[dns][timer][cancellation]")
{
    SECTION("Basic timer cancellation")
    {
        TimerService timerService; // Use default constructor
        
        std::atomic<bool> timerFired{false};
        
        // Schedule a timer for 1 second
        auto timerId = timerService.scheduleAfter(std::chrono::milliseconds(1000), [&]() {
            timerFired.store(true);
        });
        
        // Cancel it immediately
        bool cancelled = timerService.cancel(timerId);
        
        CHECK(cancelled == true);  // Should successfully cancel
        
        // Wait a bit to ensure timer doesn't fire
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        CHECK(timerFired.load() == false);  // Timer should not have fired
    }
    
    SECTION("Cancel non-existent timer")
    {
        TimerService timerService;
        
        // Try to cancel a non-existent timer
        bool cancelled = timerService.cancel(99999);
        
        CHECK(cancelled == false);  // Should return false for non-existent timer
    }
    
    SECTION("Timer fires if not cancelled")
    {
        TimerService timerService;
        
        std::atomic<bool> timerFired{false};
        
        // Schedule a very short timer
        auto timerId = timerService.scheduleAfter(std::chrono::milliseconds(10), [&]() {
            timerFired.store(true);
        });
        
        // Don't cancel it, wait for it to fire
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        CHECK(timerFired.load() == true);  // Timer should have fired
        
        // Now try to cancel the already-fired timer
        bool cancelled = timerService.cancel(timerId);
        CHECK(cancelled == false);  // Should return false for already-fired timer
    }
}