{
  description = "CNCF observability, GitOps and security stack on kind";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (s: f nixpkgs.legacyPackages.${s});
    in
    {
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            kind
            kubectl
            kubernetes-helm
            kustomize
            cilium-cli
            istioctl
            argocd
            k6
            jq
            yq-go
            just
            go
          ];
        };
      });
    };
}
