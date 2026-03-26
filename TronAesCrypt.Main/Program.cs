using System;
using System.Text;
using CommandLine;
using TronAesCrypt.Main;

var env = new ConsoleEnvironment(() =>
{
    Console.Error.Write(Resources.Enter_password_prompt);

    try
    {
        var pass = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.Error.WriteLine();
                break;
            }

            pass.Append(key.KeyChar);
        }

        return pass.ToString();
    }
    catch (InvalidOperationException)
    {
        throw new InvalidOperationException(Resources.Cannot_read_password_interactively);
    }
});

return Parser.Default.ParseArguments<Options>(args)
    .MapResult(opts => new CryptRunner(env).Run(opts), _ => 1);
