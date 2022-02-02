Gem::Specification.new do |spec|
  spec.name         = "nethttputils"
  spec.version      = "0.4.3.1"
  spec.summary      = "this tool is like a pet that I adopted young and now I depend on, sorry"
  spec.description = <<-EOF
    Back in 2015 I was a guy automating things at my job and two scripts had a common need --
    they both had to pass the same credentials to Jenkins (via query params, I guess).

    That common tool with a single method was a Net::HTTP wrapper -- that's where the name from.
    Then when the third script appeared two of them had to pass the Basic Auth.
    The verb POST was added and common logging format, and relatively complex retry logic.
    Then some website had redirects and I had to store cookies, then GZIP and API rate limits...

    I was not going to gemify this monster but it is now a dependency in many other gems,
    and since Gemfile does not support Github dependencies I have to finally gemify it.
  EOF

  spec.homepage     = "https://github.com/nakilon/nethttputils"
  spec.author       = "Victor Maslov aka Nakilon"
  spec.email        = "nakilon@gmail.com"
  spec.license      = "MIT"

  spec.require_path = "lib"
  spec.files        = %w{ LICENSE nethttputils.gemspec lib/nethttputils.rb }

  spec.add_dependency "addressable"
end
