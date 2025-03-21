# typed: false
# frozen_string_literal: true

class Gls < Formula
  desc "Support gitleaks config development and extend some gitleaks features"
  homepage "https://github.com/Finatext/gls"
  version "0.3.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Finatext/gls/releases/download/v0.3.0/gls-aarch64-apple-darwin.tar.gz"
      sha256 "aa907c4a4fdfffb0767ef72af01b440a8453311d739f5227dd4310ee55ee073b"

      def install
        bin.install "gls"
      end
    end

    on_intel do
      url "https://github.com/Finatext/gls/releases/download/v0.3.0/gls-x86_64-apple-darwin.tar.gz"
      sha256 "7cc348a7389b1922ceefd37995ce11ca6b7bbc2040ac47d2b00af39944b4d40f"

      def install
        bin.install "gls"
      end
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/Finatext/gls/releases/download/v0.3.0/gls-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "bb759786106647620681f8281aae02070b8a951429db9b3c0fdfdd93b39ea8c3"

      def install
        bin.install "gls"
      end
    end

    on_arm do
      url "https://github.com/Finatext/gls/releases/download/v0.3.0/gls-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "20fc4608408b9cbdfd5ca6f4ffd3d794a4473feca1a930a11c42e7a33aa7d1f4"

      def install
        bin.install "gls"
      end
    end
  end

  test do
    system "#{bin}/gls --version"
  end
end
