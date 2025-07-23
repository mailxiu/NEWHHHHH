package com.bss.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.bss.entity.Record;
import com.bss.mapper.RecordMapper;
import com.bss.service.RecordService;
import javax.annotation.Resource;
import org.springframework.stereotype.Service;

@Service
public class RecordServiceImpl extends ServiceImpl<RecordMapper, Record> implements RecordService {
  @Resource
  private RecordMapper recordMapper;
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\service\impl\RecordServiceImpl.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */