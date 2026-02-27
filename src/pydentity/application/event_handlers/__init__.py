from pydentity.application.event_handlers.revoke_sessions_on_deactivation import (
    RevokeSessionsOnDeactivation,
)
from pydentity.application.event_handlers.revoke_sessions_on_password_reset import (
    RevokeSessionsOnPasswordReset,
)
from pydentity.application.event_handlers.revoke_sessions_on_suspension import (
    RevokeSessionsOnSuspension,
)
from pydentity.application.event_handlers.send_welcome_email_on_registration import (
    SendWelcomeEmailOnRegistration,
)

__all__ = [
    "RevokeSessionsOnDeactivation",
    "RevokeSessionsOnPasswordReset",
    "RevokeSessionsOnSuspension",
    "SendWelcomeEmailOnRegistration",
]
