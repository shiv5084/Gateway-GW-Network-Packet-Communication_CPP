#include "nibble_swap_transform.hpp"

namespace gw {

void NibbleSwapTransform::apply(uint8_t *data, size_t length) const {
  if (data == nullptr || length == 0) {
    return;
  }

  for (size_t i = 0; i < length; ++i) {
    data[i] =
        static_cast<uint8_t>(((data[i] & 0x0F) << 4) | ((data[i] & 0xF0) >> 4));
  }
}

void NibbleSwapTransform::apply(std::vector<uint8_t> &data) const {
  apply(data.data(), data.size());
}

} // namespace gw
