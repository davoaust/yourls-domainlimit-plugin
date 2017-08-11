yourls-domainlimit-plugin
=========================

This plugin for [YOURLS](https://github.com/YOURLS/YOURLS) limits the creation of shorturls to a list of domains that you define.

You might want to limit the domains allowed for shortlinks so that your brand is not misused by people linking to resources outside your domain and outside your control.

Integrated settings page from [quantumweb.co fork](https://bitbucket.org/quantumwebco/domain-limiter-yourls-plugin)

Installation
------------
1. Download the [latest release](https://github.com/davoaust/yourls-domainlimit-plugin/releases)
1. Copy the plugin folder into your user/plugins folder for YOURLS.
1. Activate the plugin with the plugin manager in the admin interface.

Configuration
-------------
Define a list of allowed domains and excluded domains on "Domain Limiter Settings" page in admin.

You can target subdomains using a wildcard asterix before the parent domain, otherwise it reverts to exact matching.
Eg. `*.my.parent.domain` will target all the related subdomains

You may also optionally specify a list of usernames that are exempt from this restriction in the config.php file
`domainlimit_exempt_users = array( 'bobadmin' );`

License
-------

[davoaust/yourls-domainlimit-plugin](https://github.com/davoaust/yourls-domainlimit-plugin/releases)

Copyright 2017 Queensland University of Technology (david.lang@qut.edu.au)

Copyright 2017 quantumweb.co

Forked from [baldwicc/yourls-domainlimit-plugin](https://github.com/baldwicc/yourls-domainlimit-plugin/releases)

Copyright 2016 Queensland University of Technology (c1.baldwin@qut.edu.au)

Forked from [nicwaller/yourls-domainlimit-plugin](https://github.com/nicwaller/yourls-domainlimit-plugin/releases)

Copyright 2013 Nicholas Waller (code@nicwaller.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
