let sharedCounter = 0;

export function nextValue() {
  sharedCounter += 1;
  return sharedCounter;
}
