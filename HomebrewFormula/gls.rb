# typed: false
# frozen_string_literal: true

class Gls < Formula
  desc "Support gitleaks config development and extend some gitleaks features"
  homepage "https://github.com/Finatext/gls"
  version "0.2.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Finatext/gls/releases/download/v0.2.0/gls-aarch64-apple-darwin.tar.gz"
      sha256 "9cffb3e4a439c5738200655dc210640b3bb5d4d0bffbd2fa1f20744e48eebe91"

      def install
        bin.install "gls"
      end
    end

    on_intel do
      url "https://github.com/Finatext/gls/releases/download/v0.2.0/gls-x86_64-apple-darwin.tar.gz"
      sha256 "6cbc3b9e3c1c107d3e69e7ac2604a66bb4f59e2496270bef17cae9b83eda157a"

      def install
        bin.install "gls"
      end
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/Finatext/gls/releases/download/v0.2.0/gls-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "3df135901236f631b206fef16c995a2cbf394c717b9da4211a962dba78c72d6e"

      def install
        bin.install "gls"
      end
    end

    on_arm do
      url "https://github.com/Finatext/gls/releases/download/v0.2.0/gls-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "b0bcde27396803b0fe6ade795a91e4ee436dea48c26d6d8c5ca0d758af54d339"

      def install
        bin.install "gls"
      end
    end
  end

  test do
    system "#{bin}/gls --version"
  end
end
