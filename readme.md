# minimalism-service-security

**minimalism-service-security** is a service for [minimalism](https://github.com/carlonicora/minimalism) to manage
password security and to manage signature of API calls

## Getting Started

To use this library, you need to have an application using minimalism. This library does not work outside this scope.

### Prerequisite

You should have read the [minimalism documentation](https://github.com/carlonicora/minimalism/readme.md) and understand
the concepts of services in the framework.

### Installing

Require this package, with [Composer](https://getcomposer.org/), in the root directory of your project.

```
$ composer require carlonicora/minimalism-service-security
```

or simply add the requirement in `composer.json`

```json
{
    "require": {
        "carlonicora/minimalism-service-security": "~1.0"
    }
}
```

## Deployment

This service does not requires any parameter in your `.env` file in order to work. It accepts, however, a custom header
name to use to carry the call signature.

### Optional parameters

```dotenv
#custom signature name
MINIMALISM_SERVICE_SECURITY_HEADER_SIGNATURE=
```

## Build With

* [minimalism](https://github.com/carlonicora/minimalism) - minimal modular PHP MVC framework

## Versioning

This project use [Semantiv Versioning](https://semver.org/) for its tags.

## Authors

* **Carlo Nicora** - Initial version - [GitHub](https://github.com/carlonicora) |
[phlow](https://phlow.com/@carlo)
* **Sergey Kuzminich** - maintenance and expansion - [GitHub](https://github.com/aldoka) |

# License

This project is licensed under the [MIT license](https://opensource.org/licenses/MIT) - see the
[LICENSE.md](LICENSE.md) file for details 

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)