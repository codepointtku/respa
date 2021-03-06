import logging
from enum import Enum

logger = logging.getLogger(__name__)

def operations_for_reservation_sync(changes):
    """Returns list of operations that would synchronise the given changes between systems.
    Changes is expected to be a list of id-state-tuplet pairs. Each tuplet represents the
    item in either Respa (first one) or in other system (second one). Caller is expected to
    align dependant items together.

    [
     ((respa id, status), (other id,status)), # Item exist in both systems
     (None, (other id,status)),               # Item exist in remote system only
     ((respa id, status), None),              # Item exist in Respa only
     ...
    ]

    Returned operations are actions which can be interpreted using ActionVisitor

    """
    ops = []

    for pair in changes:
        respa_id, respa_state = pair[0] if pair[0] else (None, None)
        remote_id, remote_state = pair[1] if pair[1] else (None, None)

        try:
            fn = reservationSyncActions[respa_state][remote_state]
            result = fn(respa_id, remote_id)
            logger.info("{} ({}) + ({}) {} -> {}", respa_id, respa_state, remote_state, remote_id, result)
            if result:
                ops.append(result)
        except KeyError:
            pass

    return ops


class SyncActionVisitor:
    """Visitor for sync actions. Implement this protocol to perform synchronisation operations (SyncAction)."""

    def create_event(self, target, source_id):
        pass

    def delete_event(self, target, target_id):
        pass

    def update_event(self, target, source_id, target_id):
        pass

    def remove_mapping(self, respa_id, remote_id):
        pass


class SyncAction:
    def __eq__(self, other):
        """Action is equal when internal fields are equal"""
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        return False

    def __str__(self):
        """Creates string representation that looks like this:
             Class{'field1': 'value2', 'field2': 'value2'}
        """
        class_name = str(self.__class__.__name__)
        return class_name + str({k: v for k, v in self.__dict__.items()})


class CreateEvent(SyncAction):
    def __init__(self, target, source_system_id):
        self.__target = target
        self.__source_id = source_system_id

    def accept(self, visitor):
        visitor.create_event(target=self.__target, source_id=self.__source_id)


class UpdateEvent(SyncAction):
    def __init__(self, target, target_system_id, source_system_id):
        self.__target = target
        self.__target_id = target_system_id
        self.__source_id = source_system_id

    def accept(self, visitor):
        visitor.update_event(target=self.__target, target_id=self.__target_id, source_id=self.__source_id)


class DeleteEvent(SyncAction):
    def __init__(self, target, target_system_id):
        self.__target = target
        self.__target_id = target_system_id

    def accept(self, visitor):
        visitor.delete_event(target=self.__target, target_id=self.__target_id)


class RemoveMapping(SyncAction):
    def __init__(self, respa_id, remote_id):
        self.__respa_id = respa_id
        self.__remote_id = remote_id

    def accept(self, visitor):
        visitor.remove_mapping(respa_id=self.__respa_id, remote_id=self.__remote_id)


class ChangeType(Enum):
    NO_CHANGE = 1
    CREATED = 2
    UPDATED = 3
    DELETED = 4


class TargetSystem(Enum):
    RESPA = 1
    REMOTE = 2


def build_reservation_sync_actions_dict():

    REMOTE = TargetSystem.REMOTE
    RESPA = TargetSystem.RESPA

    def to(target, fn):
        def wrapper(*args):
            return fn(target, *args)
        return wrapper

    def nop(respa_id, remote_id):
        pass

    def delete(target, respa_id, remote_id):
        if target == TargetSystem.RESPA:
            return DeleteEvent(TargetSystem.RESPA, target_system_id=respa_id)
        else:
            return DeleteEvent(TargetSystem.REMOTE, target_system_id=remote_id)

    def create(target, respa_id, remote_id):
        if target == TargetSystem.RESPA:
            return CreateEvent(TargetSystem.RESPA, source_system_id=remote_id)
        else:
            return CreateEvent(TargetSystem.REMOTE, source_system_id=respa_id)

    def update(target, respa_id, remote_id):
        if target == TargetSystem.RESPA:
            return UpdateEvent(TargetSystem.RESPA, source_system_id=remote_id, target_system_id=respa_id)
        else:
            return UpdateEvent(TargetSystem.REMOTE, source_system_id=respa_id, target_system_id=remote_id)

    def removeMapping(respa_id, remote_id):
        return RemoveMapping(respa_id, remote_id)

    statesToAction = {
        None: {
            ChangeType.NO_CHANGE: to(RESPA, create),
            ChangeType.CREATED:   to(RESPA, create),
            ChangeType.UPDATED:   to(RESPA, create),
            ChangeType.DELETED:   nop},
        ChangeType.NO_CHANGE: {
            None:                 to(REMOTE, create),
            ChangeType.NO_CHANGE: nop,
            ChangeType.CREATED:   to(RESPA,  update),
            ChangeType.UPDATED:   to(RESPA,  update),
            ChangeType.DELETED:   to(RESPA,  delete)},
        ChangeType.CREATED: {
            None:                 to(REMOTE, create),
            ChangeType.NO_CHANGE: to(REMOTE, update),
            ChangeType.CREATED:   to(REMOTE, update),
            ChangeType.UPDATED:   to(REMOTE, update),
            ChangeType.DELETED:   to(REMOTE,  create)},
        ChangeType.UPDATED: {
            None:                 to(REMOTE, create),
            ChangeType.NO_CHANGE: to(REMOTE, update),
            ChangeType.CREATED:   to(REMOTE, update),
            ChangeType.UPDATED:   to(REMOTE, update),
            ChangeType.DELETED:   to(REMOTE, create)},
        ChangeType.DELETED: {
            None:                 nop,
            ChangeType.NO_CHANGE: to(REMOTE, delete),
            ChangeType.CREATED:   to(REMOTE, delete),
            ChangeType.UPDATED:   to(REMOTE, delete),
            ChangeType.DELETED:   removeMapping}
    }
    return statesToAction


reservationSyncActions = build_reservation_sync_actions_dict()

