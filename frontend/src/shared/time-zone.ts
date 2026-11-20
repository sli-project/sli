import { createContext, useContext } from "react";

export type TimeZoneState = { timeZone: string; setTimeZone: (value: string) => void };
export const DEFAULT_TIME_ZONE = "Asia/Novosibirsk";
export const TimeZoneContext = createContext<TimeZoneState>({ timeZone: DEFAULT_TIME_ZONE, setTimeZone: () => undefined });
export const useTimeZone = () => useContext(TimeZoneContext);
