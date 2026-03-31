using System;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using TronAesCrypt.Main;

var env = new ConsoleEnvironment(() =>
{
    if (Console.IsInputRedirected)
    {
        throw new InvalidOperationException(Resources.Cannot_read_password_interactively);
    }

    try
    {
        Console.Error.Write(Resources.Enter_password_prompt);

        var pass = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.Error.WriteLine();
                break;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (pass.Length > 0)
                {
                    pass.Length--;
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                pass.Append(key.KeyChar);
            }
        }

        return pass.ToString();
    }
    catch (InvalidOperationException)
    {
        throw new InvalidOperationException(Resources.Cannot_read_password_interactively);
    }
});

return await Parser.Default.ParseArguments<Options>(args)
    .MapResult(async opts => await new CryptRunner(env).RunAsync(opts), _ => Task.FromResult(1));
