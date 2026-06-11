{
  description = "dev env";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1"; # tracks nixpkgs unstable branch
    devshell.url = "github:numtide/devshell";
    devshell.inputs.nixpkgs.follows = "nixpkgs";
    devenv.url = "github:ramblurr/nix-devenv";
    devenv.inputs.nixpkgs.follows = "nixpkgs";
    clj-helpers.url = "github:outskirtslabs/clojure-nix-locker-helpers";
    clj-helpers.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    inputs@{
      self,
      devenv,
      devshell,
      clj-helpers,
      ...
    }:
    let
      package =
        pkgs:
        clj-helpers.lib.mkCljLib {
          inherit pkgs;
          name = "client-ip";
          version = "0.1.1";
          src = ./.;
          jdk = pkgs.jdk21;
          extraSrcExcludes = [ "example-project" ];
          prepAliases = [
            "kaocha"
            "build"
          ];
          prefetchAliases = [ "kaocha" ];
          checkCommand = "clojure -Srepro -M:kaocha";
          gitRev = clj-helpers.lib.gitRev self;
        };
    in
    devenv.lib.mkFlake ./. {
      inherit inputs;

      withOverlays = [
        devshell.overlays.default
        devenv.overlays.default
      ];

      packages = {
        default = package;
        # regenerates ./deps-lock.json: `nix run .#locker`
        locker = pkgs: (package pkgs).locker;
      };

      devShell =
        pkgs:
        let
          jdkPackage = pkgs.jdk21;
          clojure = pkgs.clojure.override { jdk = jdkPackage; };
        in
        pkgs.devshell.mkShell {
          imports = [
            devenv.capsules.base
          ];
          packages = [
            self.packages.${pkgs.system}.locker
            clojure
            jdkPackage
            pkgs.clojure-lsp
            pkgs.clj-kondo
            pkgs.cljfmt
            pkgs.babashka
            pkgs.git
          ];
        };

      treefmtConfig = {
        programs = {
          nixfmt.enable = true;
          cljfmt.enable = true;
        };
      };
    };
}
