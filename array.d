/**
 * Array utilities
 */

module array;

import std.algorithm;
import std.traits;

/**
 * Replicate a given element n times
 *
 * Template params:
 *      T = The element type
 *
 * Params:
 *      n = The number of elements
 *      e = The element to replicate
 *
 * Returns:
 *      An array containing the element e n times
 */

T[] replicate ( T ) ( size_t n, T e )
{
    T[] result;

    for ( auto _ = 0; _ < n; _++ )
    {
        result ~= e;
    }

    return result;
}

unittest
{
    assert(replicate(0, 1) == []);
    assert(replicate(1, 1) == [1]);
    assert(replicate(4, "hello") == ["hello", "hello", "hello", "hello"]);
}

/**
 * Check if an array contains a given element
 *
 * Template params:
 *      T = The element type
 *
 * Params:
 *      arr = The array
 *      e = The element to search for
 *
 * Returns:
 *      True if the array contains the element
 */

bool contains ( T ) ( T[] arr, T e )
{
    return arr.find(e).length > 0;
}

unittest
{
    assert(![].contains(1));
    assert([1].contains(1));
    assert([0,1,2,3,4,5].contains(3));
    assert(![0,1,2,3,4,5].contains(6));
}

/**
 * Check if the elements of two dynamic arrays are equal
 *
 * Template params:
 *      T = The element type
 *
 * Params:
 *      arr1 = The first array
 *      arr2 = The second array
 *
 * Returns:
 *      True if the arrays are equal
 */

bool arrayEquals ( T ) ( T[] arr1, T[] arr2 )
{
    if ( arr1.length != arr2.length ) return false;

    for ( auto i = 0; i < arr1.length; i++ )
    {
        if ( arr1[i] != arr2[i] )
        {
            return false;
        }
    }

    return true;
}

/**
 * Flatten a multi-dimensional array
 *
 * Template params:
 *      T = The element type
 *
 * Params:
 *      arr = The array to flatten
 *
 * Returns:
 *      The flattened array
 */

T[] flatten ( T ) ( T[][] arr )
{
    T[] result;

    foreach ( a; arr )
    {
        result ~= a;
    }

    return result;
}

unittest
{
    assert([].flatten() == []);
    assert([[], []].flatten() == []);
    assert([[1, 2, 3], [4, 5], [6]].flatten() == [1, 2, 3, 4, 5, 6]);
}

/**
 * Remove all elements contained in the given array
 *
 * Template params:
 *      T = The element type
 *
 * Params:
 *      arr = The array to remove from
 *      set = The set of elements to remove
 *
 * Returns:
 *      The array with elements removed
 */

T[] removeAll ( T ) ( T[] arr, T[] set )
{
    T[] result;

    foreach ( e; arr )
    {
        if ( !set.contains(e) )
        {
            result ~= e;
        }
    }

    return result;
}

unittest
{
    assert([].removeAll!int([]) == []);
    assert("".removeAll("hello") == []);
    assert("hello".removeAll([]) == "hello");
    assert("hello".removeAll("bye") == "hllo");
    assert("hello".removeAll("el") == "ho");
}

/**
 * Filter the array with the given predicate
 *
 * Template params:
 *      Predicate = The predicate function
 *      T = The element type
 *
 * Params:
 *      arr = The array to filter
 *
 * Returns:
 *      The filtered array
 */

T[] arrayFilter ( alias Predicate, T ) ( T[] arr )
{
    T[] result;

    foreach ( e; arr )
    {
        if ( Predicate(e) )
        {
            result ~= e;
        }
    }

    return result;
}

unittest
{
    import std.ascii;

    assert("".arrayFilter!isAlpha == "");
    assert("123abc6qq".arrayFilter!isAlpha == "abcqq");
}

/**
 * Map the given function on the given array
 *
 * Template params:
 *      Mapper = The function to map
 *      T = The input element type
 *      U = The output element type
 *
 * Params:
 *      arr = The array to map
 *
 * Returns:
 *      The mapped array
 */

U[] arrayMap ( alias Mapper, T, U ) ( T[] arr )
{
    U[] result;

    foreach ( e; arr )
    {
        result ~= Mapper(e);
    }

    return result;
}

/**
 * Split the given array into n-sized sub arrays, pad the last
 * array with the given element if necessary
 *
 * Template params:
 *      T = The element type
 *
 * Params:
 *      arr = The array
 *      n = The sub array size
 *      pad = The element to pad with
 *
 * Returns:
 *      The split and padded multi-dimensional array
 */

T[][] paddedSplitN ( T ) ( T[] arr, size_t n, T pad )
{
    T[][] result;

    for ( auto i = 0; i < arr.length; i += n )
    {
        if ( i + n > arr.length )
        {
            T[] last_elem = arr[i .. $];
            last_elem ~= replicate(i + n - arr.length, pad);

            result ~= last_elem;
        }
        else
        {
            result ~= arr[i .. i + n];
        }
    }

    return result;
}

unittest
{
    assert([].paddedSplitN!int(3, 1) == []);
    assert("Hello World!".paddedSplitN(3, ' ') == ["Hel", "lo ", "Wor", "ld!"]);
    assert("Hello World!!".paddedSplitN(3, ' ') == ["Hel", "lo ", "Wor", "ld!", "!  "]);
}

/**
 * Transpose a multi-dimensional array
 *
 * All sub-arrays must be of the same length
 *
 * Template params:
 *      T = The element type
 *
 * Params:
 *      arr = The array to transpose
 *
 * Returns:
 *      The transposed array
 */

T[][] transpose ( T ) ( T[][] arr )
{
    if ( arr.length == 0 ) return arr;

    auto new_len = arr[0].length;
    T[][] result;
    result.length = new_len;

    foreach ( a; arr )
    {
        foreach ( i, e; a )
        {
            result[i] ~= e;
        }
    }

    return result;
}

unittest
{
    assert([].transpose!int() == []);
    assert([[1, 2, 3], [4, 5, 6]].transpose() == [[1, 4], [2, 5], [3, 6]]);
}

/**
 * Call the aliased function on each given element with each of the other
 * elements as the argument, return the results in an array
 *
 * Template params:
 *      Fn = The function to call
 *      U = The return type of the function
 *      T = The function argument type
 *
 * Params:
 *      args = The argument array
 *
 * Returns:
 *      An array of the results of the combination
 */

U[] combine ( alias Fn, U, T ) ( T[] args )
{
    U[] result;

    for ( auto i = 0; i < args.length - 1; i++ )
    {
        for ( auto j = i + 1; j < args.length; j++ )
        {
            result ~= Fn(args[i], args[j]);
        }
    }

    return result;
}

unittest
{
    uint add ( uint x, uint y )
    {
        return x + y;
    }

    alias combineAdd = combine!(add, uint, uint);

    assert(combineAdd([]) == []);
    assert(combineAdd([1]) == []);
    assert(combineAdd([1, 2]) == [3]);
    assert(combineAdd([1, 2, 3]) == [3, 4, 5]);
    assert(combineAdd([1, 2, 3, 4]) == [3, 4, 5, 5, 6, 7]);
}

/**
 * Calculate the average of the given array of numbers
 *
 * Template params:
 *      N = The numeric type
 *
 * Params:
 *      arr = The number array
 *
 * Returns:
 *      The average of the numbers
 */

double average ( N ) ( N[] arr )
{
    static assert(isNumeric!N);

    if ( arr.length == 0 ) return 0;

    double result = 0;

    foreach ( n; arr )
    {
        result += n;
    }

    return result / arr.length;
}

unittest
{
    assert(average!int([]) == 0);
    assert(average([1, 2, 3]) == 2);
    assert(average([1, 2, 3, 4]) == 2.5);
}
