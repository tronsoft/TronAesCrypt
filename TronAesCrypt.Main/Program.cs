using System;
using System.Text;
using CommandLine;
using TronAesCrypt.Main;

var env = new ConsoleEnvironment(() =>
{
    var pass = new StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(true);
        if (key.Key == ConsoleKey.Enter)
        {
            break;
        }

        pass.Append(key.KeyChar);
    }

    return pass.ToString();
});

return Parser.Default.ParseArguments<Options>(args)
    .MapResult(opts => new CryptRunner(env).Run(opts), _ => 1);
