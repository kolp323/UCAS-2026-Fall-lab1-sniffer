#pragma once

#include "parser.h"
#include <functional>

namespace lab1 {
using DisplayPredicate = std::function<bool(const Packet&)>;

// Missing fields compare false, including for !=. NOT negates the predicate.
DisplayPredicate compileDisplayFilter(const QString& expression, QString& error);
}

