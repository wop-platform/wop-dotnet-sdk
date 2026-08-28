// netstandard2.0 polyfill：KeyValuePair Deconstruct（netcore 由运行时扩展提供）。
#if NETSTANDARD2_0
namespace System.Collections.Generic
{
    internal static class KeyValuePairDeconstructExtensions
    {
        internal static void Deconstruct<TKey, TValue>(this KeyValuePair<TKey, TValue> kv,
            out TKey key, out TValue value)
        {
            key = kv.Key;
            value = kv.Value;
        }
    }
}
#endif
