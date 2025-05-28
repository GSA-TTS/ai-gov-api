import asyncio
import argparse
import sys

try:
    from app.auth.schemas import APIKeyNew, Scope, Role
    from app.auth.utils import generate_api_key
    from app.users.schemas import UserCreate
    from app.users.repositories import UserRepository
    from app.auth.repositories import APIKeyRepository
    from app.db.session import async_session
except ImportError as e:
    print(f"Error importing application modules: {e}")
    print("Please make sure the script is run from the correct directory "
          "you probably need to have venv activated or"
          "use `uv run` (see Readme)")
    sys.exit(1)

SCOPES = [Scope.MODELS_INFERENCE, Scope.MODELS_EMBEDDING, Scope.ADMIN]
KEY_PREFIX = "test_adm"

async def create_admin_user(email: str, name: str, key_length: int):
    """
    Creates an admin user and an associated API key.
    """

    secret_key, key_hash = generate_api_key(KEY_PREFIX, key_length)
    async with async_session() as session:
        try:
            async with session.begin():
                user_repo = UserRepository(session)
                existing_user = await user_repo.get_by_email(email)
                if existing_user:
                    raise ValueError(f"User with email '{email}' already exists.")

                user_schema = UserCreate(
                    email=email,
                    name=name,
                    role=Role.ADMIN, 
                )
                created_user_orm = await user_repo.create(user_schema)
                if not created_user_orm.id:
                    await session.flush([created_user_orm])

                api_key_schema = APIKeyNew(
                    hashed_key=key_hash,
                    key_prefix=KEY_PREFIX,
                    manager_id=created_user_orm.id,
                    scopes=SCOPES
                )
                await APIKeyRepository(session).create(api_key_schema)
            await session.refresh(created_user_orm)

            print("\n" + "=" * 50)
            print("  ADMIN USER AND API KEY CREATED SUCCESSFULLY!")
            print("  Email:", created_user_orm.email)
            print("  Name:", created_user_orm.name)
            print("  User ID:", created_user_orm.id)
            print("\n  IMPORTANT: Save the following API key. It cannot be recovered.")
            print(f"  API Key: {secret_key}")
            print("=" * 50 + "\n")

        except ValueError as ve: # 
            print(f"\nError: {ve}")
            sys.exit(1)
        except Exception as e:
            print(f"\nError during admin user creation: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Create an admin user and their API key."
    )

    parser.add_argument(
        "--email",
        type=str,
        required=True,
        help="Email address for the new admin user."
    )
    parser.add_argument(
        "--name",
        type=str,
        required=True,
        help="Full name of the new admin user."
    )
    parser.add_argument(
        "--key-length",
        type=int,
        default=12, 
        help="Length of the secret part of the API key (default: 12)."
    )

    args = parser.parse_args()

    if args.key_length <= 0:
        print("Error: --key-length must be a positive integer.", file=sys.stderr)
        sys.exit(1)

    asyncio.run(create_admin_user(
        email=args.email,
        name=args.name,
        key_length=args.key_length
    ))


if __name__ == "__main__":
    main()
