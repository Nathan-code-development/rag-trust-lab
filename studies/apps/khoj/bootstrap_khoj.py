"""Khoj bootstrap for the isolation probe. Run INSIDE the khoj container:

    docker exec -i ragtest-khoj python src/manage.py shell < bootstrap_khoj.py

Creates: an echo-backed chat model (points chat LLM at the host echo server),
a default local search (embedding) config, and 3 regular users A/B/C each with a
Bearer API token. Prints the tokens as `TOKEN <LABEL> <kk-...>` lines -- capture
them for the probe. Idempotent (get_or_create).
"""
import secrets

from khoj.database.models import (
    KhojUser, KhojApiUser, AiModelApi, ChatModel, ServerChatSettings, SearchModelConfig,
)

# 1) echo chat model (chat LLM -> host echo server)
api, _ = AiModelApi.objects.get_or_create(
    name="echo",
    defaults=dict(api_key="placeholder", api_base_url="http://host.docker.internal:8765/v1"),
)
cm, _ = ChatModel.objects.get_or_create(
    name="echo-chat",
    defaults=dict(friendly_name="echo-chat", model_type="openai", price_tier="free",
                  ai_model_api=api, max_prompt_size=4096, tokenizer=None),
)
scs = ServerChatSettings.objects.first() or ServerChatSettings.objects.create()
scs.chat_default = cm
scs.chat_advanced = cm
scs.save()
print("CHATMODEL", cm.friendly_name, "ok")

# 2) search / embedding config (default local gte-small, 384-dim; matches echo --dim 384 if switched)
sm, _ = SearchModelConfig.objects.get_or_create(
    name="default",
    defaults=dict(model_type="text", bi_encoder="thenlper/gte-small"),
)
print("SEARCHMODEL", sm.bi_encoder, "ok")

# 3) three regular users + API tokens
for label in ["a", "b", "c"]:
    email = f"{label}@test.local"
    u = KhojUser.objects.filter(email=email).first()
    if not u:
        try:
            u = KhojUser.objects.create_user(username=email, email=email, password="Passw0rd!123")
        except TypeError:
            u = KhojUser.objects.create(username=email, email=email)
    tok = KhojApiUser.objects.filter(user=u).first()
    if not tok:
        tok = KhojApiUser.objects.create(user=u, name="iso", token="kk-" + secrets.token_urlsafe(32))
    print(f"TOKEN {label.upper()} {tok.token}")

print("BOOTSTRAP_DONE")
