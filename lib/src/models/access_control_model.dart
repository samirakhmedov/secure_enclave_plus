import 'package:json_annotation/json_annotation.dart';

import '../constants/access_control_option.dart';

part 'access_control_model.g.dart';

@JsonSerializable()
class AccessControlModel {
  final String? password;
  final List<AccessControlOption> options;
  final String tag;

  AccessControlModel._({
    required this.options,
    required this.tag,
    this.password,
  });

  factory AccessControlModel({
    String? password,
    required String tag,
    required List<AccessControlOption> options,
  }) {
    return AccessControlModel._(password: password, tag: tag, options: options);
  }

  factory AccessControlModel.fromJson(Map<String, dynamic> json) =>
      _$AccessControlModelFromJson(json);

  Map<String, dynamic> toJson() => _$AccessControlModelToJson(this);
}
