from uuid import UUID, uuid7

from pydentity.application.services.id_generator import IdGenerator


class UUIDV7IdGenerator(IdGenerator):
    def generate(self) -> UUID:
        return uuid7()
