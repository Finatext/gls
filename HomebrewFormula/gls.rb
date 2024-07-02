# typed: false
# frozen_string_literal: true

class Gls < Formula
  desc "Support gitleaks config development and extend some gitleaks features"
  homepage "https://github.com/Finatext/gls"
  version "0.1.17"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Finatext/gls/releases/download/v0.1.17/gls-aarch64-apple-darwin.tar.gz"
      sha256 "484797abf2fcaedca85840cf702551458355c1c449731256c8a3d4ae0ad72a77"

      def install
        bin.install "gls"
      end
    end

    on_intel do
      url "https://github.com/Finatext/gls/releases/download/v0.1.17/gls-x86_64-apple-darwin.tar.gz"
      sha256 "a824de42d283dcea0f93abbafdd13add9e65ad1b09cc634d13c9bfbd3eacc3b9"

      def install
        bin.install "gls"
      end
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/Finatext/gls/releases/download/v0.1.17/gls-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "c0288c96c7d9949575f13fce7e69eaa93ef127719227ab084807cee6487278d8"

      def install
        bin.install "gls"
      end
    end

    on_arm do
      url "https://github.com/Finatext/gls/releases/download/v0.1.17/gls-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "950b9e400d3b7569eed6e7932fd7dddef99d70043291fd85ffe1662b32717225"

      def install
        bin.install "gls"
      end
    end
  end

  test do
    system "#{bin}/gls --version"
  end
end
