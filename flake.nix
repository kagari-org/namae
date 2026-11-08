{
  outputs = inputs@{
    self, nixpkgs, flake-parts,
  }: flake-parts.lib.mkFlake { inherit inputs; } {
    systems = [ "x86_64-linux" "aarch64-linux" ];
    perSystem = { pkgs, ... }: {
      packages.default = pkgs.rustPlatform.buildRustPackage {
        pname = "namae";
        version = "0.1.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        doCheck = true;
        meta.description = "decentralized DNS service";
      };

      devShells.default = pkgs.mkShell {
        buildInputs = with pkgs; [];
        nativeBuildInputs = with pkgs; [ rustc cargo clippy rustfmt ];
      };
    };
  };
}
