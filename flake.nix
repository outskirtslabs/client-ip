{
  description = "dev env";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1"; # tracks nixpkgs unstable branch
    devshell.url = "github:numtide/devshell";
    devshell.inputs.nixpkgs.follows = "nixpkgs";
    devenv.url = "github:ramblurr/nix-devenv";
    devenv.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    inputs@{
      self,
      devenv,
      devshell,
      ...
    }:
    let
      jdk = "jdk21";
      projectSrc =
        pkgs:
        let
          root = toString ./.;
        in
        pkgs.lib.cleanSourceWith {
          src = ./.;
          filter =
            path: _type:
            let
              rel = pkgs.lib.removePrefix (root + "/") (toString path);
              base = builtins.baseNameOf path;
            in
            !(
              base == ".git"
              || rel == "result"
              || rel == ".nrepl-port"
              || pkgs.lib.hasPrefix ".clj-kondo/" rel
              || pkgs.lib.hasPrefix ".cpcache/" rel
              || pkgs.lib.hasPrefix ".direnv/" rel
              || pkgs.lib.hasPrefix ".lsp/" rel
              || pkgs.lib.hasPrefix "example-project/" rel
              || pkgs.lib.hasPrefix "target/" rel
            );
        };
    in
    devenv.lib.mkFlake ./. {
      inherit inputs;

      withOverlays = [
        devshell.overlays.default
        devenv.overlays.default
      ];

      packages = {
        default =
          pkgs:
          let
            jdkPackage = pkgs.${jdk};
            clojure = pkgs.clojure.override { jdk = jdkPackage; };
            src = projectSrc pkgs;
            gitRev =
              if self ? rev then
                self.rev
              else if self ? dirtyRev then
                self.dirtyRev
              else
                "dirty";
            clojureLocker = devenv.clojure.mkLockfile {
              inherit pkgs src;
              jdk = jdkPackage;
              lockfile = "./deps-lock.json";
              extraPrepInputs = [ pkgs.git ];
            };
          in
          pkgs.stdenv.mkDerivation {
            pname = "client-ip";
            version = "0.1.1";
            inherit src;
            nativeBuildInputs = [
              clojure
              pkgs.coreutils
              pkgs.findutils
              pkgs.git
              jdkPackage
            ];
            GIT_REV = gitRev;
            JAVA_HOME = jdkPackage.home;
            buildPhase = ''
              runHook preBuild

              source ${clojureLocker.shellEnv}
              export JAVA_HOME="${jdkPackage.home}"
              export JAVA_CMD="${jdkPackage}/bin/java"
              export GITLIBS="$HOME/.gitlibs"
              export JAVA_TOOL_OPTIONS="$JAVA_TOOL_OPTIONS -Djava.io.tmpdir=$TMPDIR"

              clojure -Srepro -X:deps prep :aliases '[:kaocha :build]'
              clojure -Srepro -M:kaocha
              clojure -Srepro -T:build jar

              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall

              mkdir -p "$out"
              cp "$(find target -type f -name '*.jar' -print | head -n 1)" "$out/"

              runHook postInstall
            '';
          };

        locker =
          pkgs:
          let
            jdkPackage = pkgs.${jdk};
            clojure = pkgs.clojure.override { jdk = jdkPackage; };
            src = projectSrc pkgs;
            clojureLocker = devenv.clojure.mkLockfile {
              inherit pkgs src;
              jdk = jdkPackage;
              lockfile = "./deps-lock.json";
              extraPrepInputs = [ pkgs.git ];
            };
          in
          clojureLocker.commandLocker ''
            export HOME="$tmp/home"
            export GITLIBS="$HOME/.gitlibs"
            unset CLJ_CACHE CLJ_CONFIG XDG_CACHE_HOME XDG_CONFIG_HOME XDG_DATA_HOME
            export GIT_REV="lockfile-generation"

            ${clojure}/bin/clojure -Srepro -X:deps prep :aliases "[:kaocha :build]"
            ${clojure}/bin/clojure -Srepro -P -M:kaocha
            ${clojure}/bin/clojure -Srepro -T:build jar
          '';
      };

      devShell =
        pkgs:
        let
          jdkPackage = pkgs.${jdk};
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
