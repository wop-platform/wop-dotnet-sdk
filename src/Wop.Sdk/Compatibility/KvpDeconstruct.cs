// netstandard2.0 polyfill：KeyValuePair Deconstruct（netcore 由运行时扩展提供）。
#if NETSTANDARD2_0
namespace System.Collections.Generic
{
    internal static class KeyValuePairDeconstructExtensions
    {
        /// <summary>KeyValuePair 析构扩展（netstandard2.0 polyfill，netcore 由运行时提供）。</summary>
        internal static void Deconstruct<TKey, TValue>(this KeyValuePair<TKey, TValue> kv,
            out TKey key, out TValue value)
        {
            key = kv.Key;
            value = kv.Value;
        }
    }
}
#endif
