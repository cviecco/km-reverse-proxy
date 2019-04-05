# km-reverse-proxy

[![Build Status](https://travis-ci.org/cviecco/km-reverse-proxy.svg?branch=master)](https://travis-ci.org/cviecco/km-reverse-proxy)
[![Coverage Status](https://coveralls.io/repos/github/cviecco/km-reverse-proxy/badge.svg?branch=master)](https://coveralls.io/github/cviecco/km-reverse-proxy?branch=master)

This is a simple revse proxy to use with Symantec's [keymaster][https://github.com/Symantec/keymaster] or
any other openid connect compliant identity service or any cerificate based identity service. The goal
of this project is to make integration of keymaster into other running services easier by providing
a fast a simple reverse proxy to replace their apache/nginx reverse proxies or to allow them if no authentication
is available.

It provides authentication using certificates or openid connect and can also supply coarse authorization
using ldap groups (by coarse this means path based authorization).

## Getting Started

### Building

### Installing

## Authors

* **Camilo Viecco** - *Initial work* - [cviecco](https://github.com/cviecco)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## License

This project is licensed under the Apache 2 License - see the [LICENSE](LICENSE) file for details
