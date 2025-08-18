{
  description = "";
  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1"; # tracks nixpkgs unstable branch
    flakelight.url = "github:nix-community/flakelight";
    flakelight.inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs =
    {
      self,
      flakelight,
      ...
    }:
    flakelight ./. {
      devShell =
        pkgs:
        let
          javaVersion = "21";
          jdk = pkgs."jdk${javaVersion}";
          clojure = pkgs.clojure.override { inherit jdk; };
          libraries = [ ];
        in
        {
          packages = [
            clojure
            jdk
            pkgs.clojure-lsp
            pkgs.clj-kondo
            pkgs.cljfmt
            pkgs.babashka
            pkgs.git
          ];
          env.LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath libraries;
        };

      flakelight.builtinFormatters = false;
      formatters = pkgs: {
        "*.nix" = "${pkgs.nixfmt}/bin/nixfmt";
        "*.clj" = "${pkgs.cljfmt}/bin/cljfmt fix";
      };
    };
}
