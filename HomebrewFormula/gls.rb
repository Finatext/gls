# typed: false
# frozen_string_literal: true

class Gls < Formula
  desc "Support gitleaks config development and extend some gitleaks features"
  homepage "https://github.com/Finatext/gls"
  version "0.1.16"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Finatext/gls/releases/download/v0.1.16/gls-aarch64-apple-darwin.tar.gz"
      sha256 "d4d6f6c94c280b9903a67c9bd7436cb3acbccb0563d86651ab3a768e6d25d3e7"

      def install
        bin.install "gls"
      end
    end

    on_intel do
      url "https://github.com/Finatext/gls/releases/download/v0.1.16/gls-x86_64-apple-darwin.tar.gz"
      sha256 "b59fb8afedae0eaa33f685a23ed6efecd623b9d77eab6fa093be5d95dfd01a19"

      def install
        bin.install "gls"
      end
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/Finatext/gls/releases/download/v0.1.16/gls-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "8651cf32b603356cf83454e21f3a3a377dbbb3253c0d6a0e7e80b33e0e1bc0bd"

      def install
        bin.install "gls"
      end
    end

    on_arm do
      url "https://github.com/Finatext/gls/releases/download/v0.1.16/gls-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "95bc49b542f189e1c9a0bb6f0c3dec16141233e0a540b0c29d4569916b6af881"

      def install
        bin.install "gls"
      end
    end
  end

  test do
    system "#{bin}/gls --version"
  end
end
