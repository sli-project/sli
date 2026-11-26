import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

/** Drive a styled Select whose option values are the query/form contract under test. */
export async function chooseOption(trigger: HTMLElement, value: string) {
  await userEvent.click(trigger);
  const options = await screen.findAllByRole("option");
  const option = options.find((item) => item.dataset.key === value);
  if (!option) throw new Error("Option is missing for " + value);
  await userEvent.click(option);
}
