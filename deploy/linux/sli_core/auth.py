"""Argon2 password hashing for native platform-owner bootstrap and restore."""

from argon2 import PasswordHasher


PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
