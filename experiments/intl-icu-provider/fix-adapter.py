from pathlib import Path
import sys
root=Path(sys.argv[1]).resolve()
p=root/'hermes/lib/Platform/Intl/impl_icu_provider/PlatformIntlIcuProvider.cpp'
s=p.read_text()
old='''    else if (hourCycle_ == u"h23")
      skeleton += (hour_ == eTwoDigit) ? u"KK" : u"k";
    else
      skeleton += (hour_ == eTwoDigit) ? u"HH" : u"h";'''
new='''    else if (hourCycle_ == u"h23")
      skeleton += (hour_ == eTwoDigit) ? u"HH" : u"H";
    else
      skeleton += (hour_ == eTwoDigit) ? u"KK" : u"K";'''
assert s.count(old)==1
s=s.replace(old,new)
start=s.index('  // Sort by begin position.',s.index('std::vector<Part> NumberFormatIcuProvider::formatToParts'))
end=s.index('\n  return parts;',start)
s=s[:start]+'''  // ICU integer fields contain the grouping-separator fields. Partition the
  // string at every field endpoint and choose the most specific covering field;
  // emitting each ICU range directly duplicates grouped digits.
  std::vector<int32_t> endpoints{0, static_cast<int32_t>(formatted.size())};
  for (const auto &field : fields) {
    endpoints.push_back(field.begin);
    endpoints.push_back(field.end);
  }
  std::sort(endpoints.begin(), endpoints.end());
  endpoints.erase(std::unique(endpoints.begin(), endpoints.end()), endpoints.end());
  std::vector<Part> parts;
  for (size_t i = 1; i < endpoints.size(); ++i) {
    const auto begin = endpoints[i - 1];
    const auto end = endpoints[i];
    const FieldRange *selected = nullptr;
    for (const auto &field : fields) {
      if (field.begin <= begin && field.end >= end &&
          (!selected || field.end - field.begin < selected->end - selected->begin))
        selected = &field;
    }
    const auto type = selected ? numberFieldToPartType(selected->type)
                               : std::u16string(u"literal");
    auto value = formatted.substr(begin, end - begin);
    if (!parts.empty() && parts.back().at(u"type") == type) {
      parts.back().at(u"value") += value;
    } else {
      Part part;
      part.emplace(u"type", type);
      part.emplace(u"value", std::move(value));
      parts.push_back(std::move(part));
    }
  }
''' + s[end:]
p.write_text(s)
print('Applied hour-cycle and number-field corrections')
