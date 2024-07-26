# typed: false
# frozen_string_literal: true

class Gls < Formula
  desc "Support gitleaks config development and extend some gitleaks features"
  homepage "https://github.com/Finatext/gls"
  version "0.1.18"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Finatext/gls/releases/download/v0.1.18/gls-aarch64-apple-darwin.tar.gz"
      sha256 "61a7dcc97d747994e18e1d2bbaa64ca3bca84a5cfbb149efd956c69ecce57704"

      def install
        bin.install "gls"
      end
    end

    on_intel do
      url "https://github.com/Finatext/gls/releases/download/v0.1.18/gls-x86_64-apple-darwin.tar.gz"
      sha256 "b4150f6119df445ed1d5c888455f2293564d53957e69ad4e98290ca07a47a0b3"

      def install
        bin.install "gls"
      end
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/Finatext/gls/releases/download/v0.1.18/gls-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "622af4f7ccbbe05a9fd9962db423cb9c120c4527ea2fe32a615080bbbf73fb55"

      def install
        bin.install "gls"
      end
    end

    on_arm do
      url "https://github.com/Finatext/gls/releases/download/v0.1.18/gls-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "849e78f717008925b470dc2eee3d975d1610a94fbc80f4ce9f78b2fec7371706"

      def install
        bin.install "gls"
      end
    end
  end

  test do
    system "#{bin}/gls --version"
  end
end
