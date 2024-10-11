# Tendermint based blockchain development

> **NOTE:**    
> Compared to the beacon side, this module is less maintained, some features may be outdated.

Utils for the managements of local and distributed tendermint clusters

Supported versions of [`tendermint-core`](https://github.com/tendermint/tendermint):
- branch `master`: v0.34.24

Assume your project id(name) is `$PROJECT`,

the `dev` meta path will be:
- `/__chain_dev__/tendermint_based/${PROJECT}/${HOST}/${USER}/__dev__`

the `ddev` meta path will be:
- `/__chain_dev__/tendermint_based/${PROJECT}/${HOST}/${USER}/__d_dev__`

If the `$PROJECT` is not set(empty value),

the `dev` meta path will be:
- `/__chain_dev__/tendermint_based/${HOST}/${USER}/__dev__`

the `ddev` meta path will be:
- `/__chain_dev__/tendermint_based/${HOST}/${USER}/__d_dev__`
