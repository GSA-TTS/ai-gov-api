# AI API Framework
This is a FastApi application that will be able to wrap different inference backends to simplify interacting with them.

The standard interface for chat is the OpenAI Chat Completion API. 

## Prepare for Zscaler
Run the following commands ONLY when you are under Zscaler and are having Zscaler-related SSL issues.

```bash
# Create a custom certificate bundle
cat zscaler.pem $(python -c "import certifi; print(certifi.where())") > custom-ca-bundle.pem

# Set multiple environment variables
export SSL_CERT_FILE=$(pwd)/custom-ca-bundle.pem
export REQUESTS_CA_BUNDLE=$(pwd)/custom-ca-bundle.pem
export CURL_CA_BUNDLE=$(pwd)/custom-ca-bundle.pem
export PYTHONHTTPSVERIFY=0
```

## Running Dev:

Keep uv up-to-date:
```
uv self update
```

## First time here?

### Database
You will need to have Postgres running locally (although you could probably make Sqlite work without too much trouble).

The simplest way is to just pull a docker container. We're using pgvector since we may end up storying embdeddings at some point:

```
   docker run --name pgvector_postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=postgres -p 5433:5432 pgvector/pgvector:pg15
```
Add the connection string to a .env to pull it into the settings (see .env_example).

### Running code

This project uses `uv`. You should be able to install it by following the [installation documentation](https://docs.astral.sh/uv/getting-started/installation/). The `curl` shell command is the recommended and fastest way to install uv.

Once installed you can sync the dependencies. This will automatically create a `.venv` folder, but you can generally ignore it while using uv. 
```bash
uv sync
```

Run the following command instead if Zscaler causes issues with the above command
```bash
uv sync --no-cache --allow-insecure-host github.com --allow-insecure-host githubusercontent.com
```

**Declare the LLM credentials:**
- Copy `.env_example` to `.env`
- Change the values of Amazon Bedrock and Google Vertex (see [notes_AWS_Bedrock.md](notes_AWS_Bedrock.md) and [notes_Gogle_Vertex.md](notes_Gogle_Vertex.md) for more details)

**Start the server:**

```
uv run fastapi dev
```

Running tests:

```
uv run pytest
```


## Database Migrations
This project uses alembic to manage changes to the database scheme.

Create a migration:
```
uv run alembic revision --autogenerate -m "First Migration"
```

Update tables:
```
uv run alembic upgrade head
```

## Create an API Key
You will need an API key to interact with the endpoints. There is a script `create_admin_user.py` with some code to create a user and generate and API key. API keys are not stored in the database, so look for the output on the terminal with the key and save it. Like previous commands you can run this with `uv` (or python with an active venv):

```
uv run scripts/create_admin_user.py --email admin@example.com --name "Testy Test"
```