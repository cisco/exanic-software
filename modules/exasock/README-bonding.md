# Exasock Bonding support extensions

Exasock.ko has been extended to support bonding, but only in the
active-backup mode. Furthermore it's meant to manage only bonds
containing ExaNIC devices, so it will reject attempts to bind it
to already-existing bonding interfaces which contain non-ExaNIC
devices, or to add a non-ExaNIC device to a bond which is currently
under its management.

The rest of the documentation is maintained on the website -- please see the [Exasock-bonding Extensions documentation](https://exablaze.com/docs/exanic/user-guide/bonding/)