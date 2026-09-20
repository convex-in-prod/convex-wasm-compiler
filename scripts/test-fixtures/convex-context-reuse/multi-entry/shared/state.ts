const retainedValues: string[] = [];

export function retain(value: string): void {
  retainedValues.push(value);
}
