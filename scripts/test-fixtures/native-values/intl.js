const intlGlobal: any = globalThis;
const retainedNumber: any = new intlGlobal.Intl.NumberFormat("de-DE");
const retainedDate: any = new intlGlobal.Intl.DateTimeFormat("en-GB", {
  timeZone: "UTC", year: "numeric", month: "2-digit", day: "2-digit",
});
const retainedCollator: any = new intlGlobal.Intl.Collator("en", { sensitivity: "base" });

intlGlobal.__convexNativeRuntimeProbe = function(validateIntlState: any): boolean {
  if (!validateIntlState() ||
      typeof intlGlobal.__convexWasmCaptureIntrinsicState !== "undefined" ||
      retainedNumber.format(1234.5) !== "1.234,5" ||
      retainedDate.format(0) !== "01/01/1970" ||
      retainedCollator.compare("café", "cafe") !== 0) {
    throw new Error("Native Intl formatting or intrinsic state is invalid");
  }
  for (const sign of ["+", "-", "\u2212"]) {
    for (let hour = 0; hour < 24; ++hour) {
      for (const minute of [0, 1, 30, 59]) {
        const hours = String(hour).padStart(2, "0");
        const minutes = String(minute).padStart(2, "0");
        const forms = [sign + hours + minutes, sign + hours + ":" + minutes];
        if (minute === 0) forms.push(sign + hours);
        for (const timeZone of forms) {
          const formatter: any = new intlGlobal.Intl.DateTimeFormat("en-GB", {
            timeZone, hourCycle: "h23", hour: "2-digit", minute: "2-digit",
          });
          const expectedSign = sign === "+" || (hour === 0 && minute === 0) ? "+" : "-";
          const offsetMinutes = (sign === "+" ? 1 : -1) * (hour * 60 + minute);
          const clockMinutes = (offsetMinutes + 1440) % 1440;
          const expectedClock = String(Math.floor(clockMinutes / 60)).padStart(2, "0") +
            ":" + String(clockMinutes % 60).padStart(2, "0");
          if (formatter.resolvedOptions().timeZone !== expectedSign + hours + ":" + minutes ||
              formatter.format(0) !== expectedClock) {
            throw new Error("Native Intl offset timezone normalization failed");
          }
        }
      }
    }
  }
  for (const timeZone of ["+0", "+000", "+00000", "+00:", "+24", "+24:00",
                         "+00:60", "+01:00:00", "++01", "\u2212ab", "+\u0660\u0661"]) {
    let rejected = false;
    try {
      new intlGlobal.Intl.DateTimeFormat("en-GB", { timeZone });
    } catch (error) {
      if (!(error instanceof RangeError)) throw error;
      rejected = true;
    }
    if (!rejected) throw new Error("Native Intl accepted an invalid offset timezone");
  }
  for (const name of ["NumberFormat", "DateTimeFormat", "Collator"]) {
    const constructor: any = intlGlobal.Intl[name];
    if (Reflect.defineProperty(constructor, "unexpected", { value: 1 }) ||
        Reflect.defineProperty(constructor.prototype, "unexpected", { value: 1 })) {
      throw new Error("Intl constructor or prototype accepted an extension");
    }
    const before: any = Object.getOwnPropertyDescriptor(constructor.prototype, "resolvedOptions");
    Object.defineProperty(constructor.prototype, "resolvedOptions", {
      ...before, value: function(): any { return {}; },
    });
    if (validateIntlState()) throw new Error("Native validator missed Intl method replacement");
    Object.defineProperty(constructor.prototype, "resolvedOptions", before);
    if (!validateIntlState()) throw new Error("Native validator rejected restored Intl state");
  }
  for (const constructor of [intlGlobal.Intl.NumberFormat, intlGlobal.Intl.DateTimeFormat]) {
    const before: any = Object.getOwnPropertyDescriptor(constructor.prototype, "format");
    Object.defineProperty(constructor.prototype, "format", {
      ...before, get: function(): any { return function(): string { return "changed"; }; },
    });
    if (validateIntlState()) throw new Error("Native validator missed Intl accessor replacement");
    Object.defineProperty(constructor.prototype, "format", before);
    if (!validateIntlState()) throw new Error("Native validator rejected restored Intl accessor");
  }
  return true;
};
