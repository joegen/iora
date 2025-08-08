// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include <string>
#include <sstream>
#include <memory>

#ifdef iora_USE_TIKTOKEN
#include <tiktoken/encodings.h>
#endif

namespace iora
{
namespace util
{
  /// \brief Estimates or computes token counts for input text, optionally using
  /// external encoders.
  class Tokenizer
  {
  public:
    /// \brief Counts tokens in the input text.
    int count(const std::string& text) const
    {
#ifdef iora_USE_TIKTOKEN
      if (_encoder)
      {
        auto tokens = _encoder->encode(text);
        return static_cast<int>(tokens.size());
      }
#endif
      return estimateFallback(text);
    }

  private:
#ifdef iora_USE_TIKTOKEN
    std::shared_ptr<GptEncoding> _encoder =
        GptEncoding::get_encoding(LanguageModel::CL100K_BASE);
#endif

    int estimateFallback(const std::string& text) const
    {
      int wordCount = 0;
      std::istringstream iss(text);
      std::string token;
      while (iss >> token)
      {
        wordCount++;
      }
      return static_cast<int>(wordCount * 1.5);
    }
  };
} // namespace http
} // namespace iora