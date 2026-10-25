/*
 * SumCalc.h - add up all whole numbers in a range, e.g. 1 + 2 + ... + 100.
 *
 * This is a header-only file, so you only need to `#include "SumCalc.h"` -
 * no extra .cpp file and no change to Android.mk is required.
 *
 * The function is written to be EASY TO FIND AND READ in IDA Pro when you
 * open libzc.so:
 *   extern "C"  - the symbol name stays "SumRange" (C++ would rename it to
 *                 something like "_Z8SumRangeii").
 *   noinline    - the compiler keeps it as its own function instead of
 *                 copying its body into the caller.
 *   used        - the compiler never removes it, even if it looks unused.
 *   visibility("default") - it is exported, so it shows in IDA's
 *                 "Exports" window even in the stripped libs/ build.
 * Android.mk builds with -O0, so the loop is not optimized into a formula.
 */
#ifndef SUM_CALC_H
#define SUM_CALC_H

/*
 * SumRange
 * --------
 * Adds every whole number from `start` to `end` (both included) with a
 * simple loop:
 *
 *   sum = start + (start + 1) + ... + end
 *
 * Parameters:
 *   start - first number to add, e.g. 1.
 *   end   - last number to add, e.g. 100.
 *
 * Returns:
 *   The sum. SumRange(1, 100) returns 5050.
 *   If start is bigger than end there is nothing to add, so it returns 0.
 *
 * Limits:
 *   The result is an `int` (max 2147483647). Very large ranges, e.g.
 *   SumRange(1, 100000), overflow and give a wrong number.
 *
 * Example:
 *   int total = SumRange(1, 100);   // 5050
 *   LOGI("sum = %d", total);
 */
extern "C" inline __attribute__((noinline, used, visibility("default")))
int SumRange(int start, int end)
{
  int sum = 0;
  for (int i = start; i <= end; i++)
  {
    sum += i;
  }
  return sum;
}

#endif
