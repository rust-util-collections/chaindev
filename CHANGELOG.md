# Change log

#### v0.20.x

- Support double addresses
  - A local address
  - An optional external address

#### v0.14.x

- Remove the `unix_abstract_socket` feature
  - It is not stable enough

#### v0.13.x

- Mark all ENVs as `protected` by default
  - `Destroy` / `DestroyAll` / `KickNode` is not allowed for a `protected` ENV
  - `Unprotect` operation is designed to remove the `protected` mark

......

......

......

#### v0.3.x

- Limit block size up to 1 MB, in genesis

#### v0.2.x

- Make 'Seed Node' acting as a RPC server
