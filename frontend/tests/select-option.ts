import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

/** Drive a styled Select whose option values are the query/form contract under test. */
export async function chooseOption(trigger: HTMLElement, value: string) {
  await userEvent.click(trigger);
  const option = await waitFor(() => {
    const match = screen.queryAllByRole("option").find((item) => item.dataset.key === value);
    if (!match) throw new Error("Option is missing for " + value);
    return match;
  });
  await userEvent.click(option);
}
