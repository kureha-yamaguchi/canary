import asyncio

from typing import Dict, List, Type, Union

from openai import AsyncOpenAI
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from pydantic import BaseModel
from typing import TypeVar
import os

T = TypeVar("T", bound=BaseModel)


class SemaphoreClient:
    def __init__(
        self,
        max_concurrent_requests: int = 15,
        max_retries: int = 3,
        base_wait_seconds: int = 1,
        max_wait_seconds: int = 60,
        semaphore: asyncio.Semaphore | None = None,
    ):
        self.client = AsyncOpenAI(
            api_key=os.getenv("OPENROUTER_API_KEY"),
            base_url=os.getenv("OPENROUTER_BASE_URL"),
        )
        if not semaphore:
            self.semaphore = asyncio.Semaphore(max_concurrent_requests)
        else:
            self.semaphore = semaphore

        self.max_retries = max_retries
        self.base_wait_seconds = base_wait_seconds
        self.max_wait_seconds = max_wait_seconds

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=60),
        retry=retry_if_exception_type((Exception,)),
    )
    async def _make_request(
        self,
        model: str,
        messages: List[Dict[str, str]],
        response_format: Type[T],
        index: int | None = None,
        return_full_response: bool = False,
    ) -> T:
        if index is not None:
            print(f"Making request {index}")
        response = await self.client.responses.parse(
            model=model,
            input=messages,
            text_format=response_format,
        )
        if index is not None:
            print(f"Request completed {index}")
        if return_full_response:
            return response
        else:
            return response.output_parsed

    async def parse_completion(
        self,
        model: str,
        messages: List[Dict[str, str]],
        response_format: Type[T],
        index: int | None = None,
        return_full_response: bool = False,
    ) -> T:
        async with self.semaphore:
            return await self._make_request(
                model, messages, response_format, index, return_full_response
            )

    async def batch_parse_completions(
        self,
        model: str,
        messages_list: List[List[Dict[str, str]]],
        response_format: Type[T],
        return_full_response: bool = False,
    ) -> List[Union[T, Exception]]:
        """
        Process multiple completion requests in parallel, preserving order.

        Args:
            model: The model to use for all requests
            messages_list: List of message lists, one for each request
            response_format: Pydantic model class for parsing responses

        Returns:
            List of results in the same order as inputs. Each result is either:
            - A successfully parsed Pydantic model instance
            - An Exception if the request failed
        """

        async def _single_completion(
            index: int, messages: List[Dict[str, str]]
        ) -> Union[T, Exception]:
            try:
                print(f"Making request {index}")
                return await self.parse_completion(
                    model, messages, response_format, index, return_full_response
                )
            except Exception as e:
                return e

        # Create tasks for all requests
        tasks = [
            _single_completion(index, messages)
            for index, messages in enumerate(messages_list)
        ]

        # Execute all tasks concurrently and preserve order
        results = await asyncio.gather(*tasks, return_exceptions=False)

        return results

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.close()
