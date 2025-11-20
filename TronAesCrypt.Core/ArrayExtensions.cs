namespace TRONSoft.TronAesCrypt.Core;

internal static class ArrayExtensions
{
    public static void Fill<T>(this T[] array, T value)
    {
        if (array == null)
        {
            return;
        }

        for (var i = 0; i < array.Length; i++)
        {
            array[i] = value;
        }
    }
}