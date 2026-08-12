{ pkgs, ... }: {
  languages = {
    javascript = {
      enable = true;
      package = pkgs.nodejs_24;
      nodejs.enable = true;
      corepack.enable = true;
      lsp.enable = true;
    };
    typescript = {
      enable = true;
      lsp.enable = true;
    };
  };

  enterTest = ''
    node --version
    corepack --version
    pnpm --version
  '';
}
