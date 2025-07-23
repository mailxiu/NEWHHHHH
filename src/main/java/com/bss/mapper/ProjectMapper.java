package com.bss.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.bss.entity.Project;
import java.util.List;
import org.apache.ibatis.annotations.Select;

public interface ProjectMapper extends BaseMapper<Project> {
  @Select({"select state from project where merchant = #{merchant} GROUP BY state"})
  List<String> stateList(String paramString);
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\mapper\ProjectMapper.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */