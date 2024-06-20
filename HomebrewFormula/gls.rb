# typed: false
# frozen_string_literal: true

class Gls < Formula
  desc "Support gitleaks config development and extend some gitleaks features"
  homepage "https://github.com/Finatext/gls"
  version "0.1.10"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Finatext/gls/releases/download/v0.1.10/gls-aarch64-apple-darwin.tar.gz"
      sha256 "f85e8c5c096937ea851c6f0a88fb1cf981d85d32baf6c4cbcaf29d623040e1a8"

      def install
        bin.install "gls"
      end
    end

    on_intel do
      url "https://github.com/Finatext/gls/releases/download/v0.1.10/gls-x86_64-apple-darwin.tar.gz"
      sha256 "959e84dabc2dd839cd69660b7185b2e870844f5719cb5bcafc2631b1d93a0319"

      def install
        bin.install "gls"
      end
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/Finatext/gls/releases/download/v0.1.10/gls-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "ac149a85f759c56ad7574c6112d219ad39d8c39a8253f3b09b4728308b4ae074"

      def install
        bin.install "gls"
      end
    end

    on_arm do
      url "https://github.com/Finatext/gls/releases/download/v0.1.10/gls-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "d2c0fc6aefb252c9f56bbcab2e729dcb0b83a1523eae79e7e0e5f781e22a8247"

      def install
        bin.install "gls"
      end
    end
  end

  test do
    system "#{bin}/gls --version"
  end
end
