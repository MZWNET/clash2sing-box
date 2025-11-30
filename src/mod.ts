import { Command, ValidationError } from "@cliffy/command";

import { convert, merge, type Options } from "./libs/utils.ts";

await new Command()
  .name("clash2sing-box")
  .description("Clash to sing-box configuration converter")
  .command("convert <input:string> <output:string>", "Convert configuration")
  .option(
    "--outbound.domainresolver.tag <string:string>",
    "The name of the domain resolver, required for setting resolver strategy",
  )
  .option(
    "--outbound.selector.default <integer:integer>",
    "Use the n-th outbound as the default in the selector outbound",
  )
  .option(
    "--outbound.selector.tag <string:string[]>",
    "The name(s) of the selector outbound(s)",
  )
  .option(
    "--mergeable <path:string>",
    "External configuration to merge after the conversion",
    (value: string): { value: object } => {
      try {
        return { value: JSON.parse(Deno.readTextFileSync(value)) };
      } catch (_) {
        throw new ValidationError("Invalid mergeable file");
      }
    },
  )
  .action(async (options: Options, input: string, output: string) => {
    const content = /^https?:\/\//.test(input)
      ? await (await fetch(input, { headers: { "User-Agent": "ClashMeta" } }))
        .text()
      : Deno.readTextFileSync(input);
    const converted = convert(content, options);
    if (output === "-" || output === "stdout") {
      console.log(converted);
    } else {
      Deno.writeTextFileSync(output, converted);
    }
  })
  .command("merge <input...:string>", "Merge multiple JSON files")
  .action((_: unknown, ...input: string[]) => {
    console.log(
      merge(...input.map((i) => JSON.parse(Deno.readTextFileSync(i)))),
    );
  })
  .parse(Deno.args);
