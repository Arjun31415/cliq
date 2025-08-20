{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # <https://github.com/nix-systems/nix-systems>
    systems.url = "github:nix-systems/default-linux";
  };
  outputs = inputs @ {
    self,
    nixpkgs,
    systems,
    # config,
    ...
  }: let
    inherit (nixpkgs) lib;
    eachSystem = lib.genAttrs (import systems);
    pkgsFor = eachSystem (system:
      import nixpkgs {
        localSystem = system;
      });
  in {
    devShells = eachSystem (system: {
      default = pkgsFor.${system}.mkShell {
        name = "chat-server-shell";
        # nativeBuildInputs = with pkgsFor.${system}; [];
        # hardeningDisable = ["fortify"];
        # inputsFrom = [(pkgsFor.${system}.qt6Packages.callPackage ./nix/default.nix {})];
        packages = with pkgsFor.${system}; [
          bear
          ninja
        ];
      };
    });
    formatter = eachSystem (system: nixpkgs.legacyPackages.${system}.alejandra);
  };
}
