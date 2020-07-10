# Kulkunen Abloy driver

Kulkunen has an integration for Abloy access control system. The
integration uses the Abloy API for adding access to reservations and
currently supports only PIN-code-based entry.

The Abloy driver creates a new user with a correct role for the reservations's
resource and gives a unique PIN code for the user 24 hours before reservation starts.
PIN codes are recycled which means that when a reservation is made, Abloy driver will
first try to find a previously made unused PIN code before creating a new PIN code.
PIN codes are recycled to limit the number of PIN codes and because PIN codes currently
can't be removed from Abloy via API.

When a user's reservation is over their PIN code and role related to the reservation
are removed soon after the reservation has ended.

The Abloy driver needs some instance-based configuration to work. The
configuration is stored as an JSON object in `AccessControlSystem.driver_config`.

Key            | Description
-------------- | --------------------
api_url        | The API base URL for the Abloy service
header_username | Basic auth username for the API user configured to Abloy
header_password | Basic auth password for the API user
body_username | http encoded body username for the API user configured to Abloy
body_password | http encoded body password for the API user
organization_name | name of the organization each reserver will belong to in Abloy

For each Respa resource that is managed by Abloy, an `AccessControlResource`
object needs to created with the following driver config:

Key            | Description
---------------| --------------------
access_point_group_name | Specifies which access point group to allow access to for this resource

The access point group is configured in Abloy and should contain all the access points
(doors) that need to be opened to allow the user access.
